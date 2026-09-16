rule TTP_XOR_WriteProcessMemory_cdca {
  strings:
    $key_cdca = { 9a b8 [2] a8 9a [2] ae af [2] 80 af [2] bf b3 }

  condition:
    any of them
}