rule TTP_XOR_WriteProcessMemory_9ec3 {
  strings:
    $key_9ec3 = { c9 b1 [2] fb 93 [2] fd a6 [2] d3 a6 [2] ec ba }

  condition:
    any of them
}