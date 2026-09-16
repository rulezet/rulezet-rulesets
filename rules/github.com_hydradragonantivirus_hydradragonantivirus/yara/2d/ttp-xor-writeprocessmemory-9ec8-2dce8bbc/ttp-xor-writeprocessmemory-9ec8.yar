rule TTP_XOR_WriteProcessMemory_9ec8 {
  strings:
    $key_9ec8 = { c9 ba [2] fb 98 [2] fd ad [2] d3 ad [2] ec b1 }

  condition:
    any of them
}