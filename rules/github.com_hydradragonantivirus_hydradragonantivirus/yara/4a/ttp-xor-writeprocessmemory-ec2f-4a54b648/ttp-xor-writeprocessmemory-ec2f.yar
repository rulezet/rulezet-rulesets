rule TTP_XOR_WriteProcessMemory_ec2f {
  strings:
    $key_ec2f = { bb 5d [2] 89 7f [2] 8f 4a [2] a1 4a [2] 9e 56 }

  condition:
    any of them
}