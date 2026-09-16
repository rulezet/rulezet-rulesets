rule TTP_XOR_WriteProcessMemory_ec2b {
  strings:
    $key_ec2b = { bb 59 [2] 89 7b [2] 8f 4e [2] a1 4e [2] 9e 52 }

  condition:
    any of them
}