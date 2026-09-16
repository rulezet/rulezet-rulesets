import "pe"
rule FSGCrypt: EMBRACE {
  meta:
    author = "_pusher_"
    date   = "2016-07"

  strings:
        $a0 = { 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 }
    $a2 = { 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 }
    $a1 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 80 34 08 ?? B8 46 D2 40 00 B9 ?? ?? ?? ?? 80 34 08 ?? E2 FA }
    $a3 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 80 34 08 ?? E2 FA }

  condition:
        ($a0 at 0x154 or $a2 at 0x1F2) and (pe.timestamp == 0x52424D45) and ($a1 at pe.entry_point or ($a3 in (pe.entry_point..pe.entry_point + 0x50)))
}