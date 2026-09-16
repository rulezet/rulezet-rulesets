rule TTP_XOR_QUAD_CurrentVersionRun_122c {
  strings:
    $key_122c = { 41 43 [2] 65 4d [2] 4e 61 [2] 60 43 [2] 74 58 [2] 7b 42 [2] 65 5f [2] 67 5e [2] 7c 58 [2] 60 5f [2] 7c 70 }

  condition:
    any of them
}