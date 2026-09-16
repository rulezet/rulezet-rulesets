rule TTP_XOR_WriteProcessMemory_b144 {
  strings:
    $key_b144 = { e6 36 [2] d4 14 [2] d2 21 [2] fc 21 [2] c3 3d }

  condition:
    any of them
}