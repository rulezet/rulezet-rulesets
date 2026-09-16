rule TTP_XOR_WriteProcessMemory_f852 {
  strings:
    $key_f852 = { af 20 [2] 9d 02 [2] 9b 37 [2] b5 37 [2] 8a 2b }

  condition:
    any of them
}