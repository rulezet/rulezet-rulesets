rule TTP_XOR_WriteProcessMemory_cbed {
  strings:
    $key_cbed = { 9c 9f [2] ae bd [2] a8 88 [2] 86 88 [2] b9 94 }

  condition:
    any of them
}