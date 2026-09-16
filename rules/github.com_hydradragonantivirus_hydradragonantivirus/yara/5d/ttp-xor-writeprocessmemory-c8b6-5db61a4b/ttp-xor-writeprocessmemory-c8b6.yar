rule TTP_XOR_WriteProcessMemory_c8b6 {
  strings:
    $key_c8b6 = { 9f c4 [2] ad e6 [2] ab d3 [2] 85 d3 [2] ba cf }

  condition:
    any of them
}