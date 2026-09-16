rule TTP_XOR_WriteProcessMemory_54ed {
  strings:
    $key_54ed = { 03 9f [2] 31 bd [2] 37 88 [2] 19 88 [2] 26 94 }

  condition:
    any of them
}