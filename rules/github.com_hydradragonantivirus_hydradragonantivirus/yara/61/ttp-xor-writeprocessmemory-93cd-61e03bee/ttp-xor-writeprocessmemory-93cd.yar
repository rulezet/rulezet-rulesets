rule TTP_XOR_WriteProcessMemory_93cd {
  strings:
    $key_93cd = { c4 bf [2] f6 9d [2] f0 a8 [2] de a8 [2] e1 b4 }

  condition:
    any of them
}