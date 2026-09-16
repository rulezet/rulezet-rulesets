rule TTP_XOR_WriteProcessMemory_026d {
  strings:
    $key_026d = { 55 1f [2] 67 3d [2] 61 08 [2] 4f 08 [2] 70 14 }

  condition:
    any of them
}