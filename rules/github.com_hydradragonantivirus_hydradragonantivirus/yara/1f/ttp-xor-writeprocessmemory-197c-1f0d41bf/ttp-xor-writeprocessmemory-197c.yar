rule TTP_XOR_WriteProcessMemory_197c {
  strings:
    $key_197c = { 4e 0e [2] 7c 2c [2] 7a 19 [2] 54 19 [2] 6b 05 }

  condition:
    any of them
}