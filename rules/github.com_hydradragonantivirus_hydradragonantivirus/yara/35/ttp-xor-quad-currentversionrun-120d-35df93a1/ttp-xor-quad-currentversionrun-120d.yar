rule TTP_XOR_QUAD_CurrentVersionRun_120d {
  strings:
    $key_120d = { 41 62 [2] 65 6c [2] 4e 40 [2] 60 62 [2] 74 79 [2] 7b 63 [2] 65 7e [2] 67 7f [2] 7c 79 [2] 60 7e [2] 7c 51 }

  condition:
    any of them
}