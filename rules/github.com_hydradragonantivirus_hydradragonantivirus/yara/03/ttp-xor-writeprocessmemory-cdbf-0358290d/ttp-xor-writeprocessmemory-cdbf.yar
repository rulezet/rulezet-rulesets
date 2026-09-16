rule TTP_XOR_WriteProcessMemory_cdbf {
  strings:
    $key_cdbf = { 9a cd [2] a8 ef [2] ae da [2] 80 da [2] bf c6 }

  condition:
    any of them
}