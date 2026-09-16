rule TTP_XOR_WriteProcessMemory_58fa {
  strings:
    $key_58fa = { 0f 88 [2] 3d aa [2] 3b 9f [2] 15 9f [2] 2a 83 }

  condition:
    any of them
}