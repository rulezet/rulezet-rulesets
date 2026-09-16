rule TTP_XOR_WriteProcessMemory_9ec2 {
  strings:
    $key_9ec2 = { c9 b0 [2] fb 92 [2] fd a7 [2] d3 a7 [2] ec bb }

  condition:
    any of them
}