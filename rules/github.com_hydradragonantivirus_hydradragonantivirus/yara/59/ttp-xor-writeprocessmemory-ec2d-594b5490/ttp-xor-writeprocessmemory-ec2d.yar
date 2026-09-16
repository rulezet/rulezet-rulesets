rule TTP_XOR_WriteProcessMemory_ec2d {
  strings:
    $key_ec2d = { bb 5f [2] 89 7d [2] 8f 48 [2] a1 48 [2] 9e 54 }

  condition:
    any of them
}