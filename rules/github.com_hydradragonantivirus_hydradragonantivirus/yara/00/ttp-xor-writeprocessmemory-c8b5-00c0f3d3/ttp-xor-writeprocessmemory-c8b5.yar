rule TTP_XOR_WriteProcessMemory_c8b5 {
  strings:
    $key_c8b5 = { 9f c7 [2] ad e5 [2] ab d0 [2] 85 d0 [2] ba cc }

  condition:
    any of them
}