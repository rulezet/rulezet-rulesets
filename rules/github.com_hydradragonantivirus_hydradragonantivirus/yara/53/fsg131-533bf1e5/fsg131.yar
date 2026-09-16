import "pe"
rule FSG131: dulek xt {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
        $a0 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 }

  condition:
        ($a0 at 0x188) and (pe.timestamp == 0x21475346) and
        (uint32(uint32(0x3C) + 0x84) == 0x00000034)
}