rule TTP_XOR_WriteProcessMemory_406a {
  strings:
    $key_406a = { 17 18 [2] 25 3a [2] 23 0f [2] 0d 0f [2] 32 13 }

  condition:
    any of them
}