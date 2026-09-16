rule TTP_XOR_WriteProcessMemory_dddd {
  strings:
    $key_dddd = { 8a af [2] b8 8d [2] be b8 [2] 90 b8 [2] af a4 }

  condition:
    any of them
}