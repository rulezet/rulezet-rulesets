rule PEiD_00586_EXE2COM__Method_1__ {
  meta:
    description = "[EXE2COM (Method 1)]"
    ep_only     = "true"

  strings:
    $a = { 8C DB BE ?? ?? 8B C6 B1 ?? D3 E8 03 C3 03 ?? ?? A3 ?? ?? 8C C8 05 ?? ?? A3 }

  condition:
    $a
}