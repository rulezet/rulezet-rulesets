rule TTP_XOR_WriteProcessMemory_02fe {
  strings:
    $key_02fe = { 55 8c [2] 67 ae [2] 61 9b [2] 4f 9b [2] 70 87 }

  condition:
    any of them
}