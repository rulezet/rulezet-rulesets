rule TTP_XOR_WriteProcessMemory_9e97 {
  strings:
    $key_9e97 = { c9 e5 [2] fb c7 [2] fd f2 [2] d3 f2 [2] ec ee }

  condition:
    any of them
}