rule TTP_XOR_QUAD_CurrentVersionRun_197c {
  strings:
    $key_197c = { 4a 13 [2] 6e 1d [2] 45 31 [2] 6b 13 [2] 7f 08 [2] 70 12 [2] 6e 0f [2] 6c 0e [2] 77 08 [2] 6b 0f [2] 77 20 }

  condition:
    any of them
}