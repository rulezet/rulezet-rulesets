rule TTP_XOR_WriteProcessMemory_41bf {
  strings:
    $key_41bf = { 16 cd [2] 24 ef [2] 22 da [2] 0c da [2] 33 c6 }

  condition:
    any of them
}