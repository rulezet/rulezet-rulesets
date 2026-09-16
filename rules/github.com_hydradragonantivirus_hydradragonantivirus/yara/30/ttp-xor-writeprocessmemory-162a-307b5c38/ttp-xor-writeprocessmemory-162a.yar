rule TTP_XOR_WriteProcessMemory_162a {
  strings:
    $key_162a = { 41 58 [2] 73 7a [2] 75 4f [2] 5b 4f [2] 64 53 }

  condition:
    any of them
}