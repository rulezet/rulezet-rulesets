rule TTP_XOR_QUAD_CurrentVersionRun_272c {
  strings:
    $key_272c = { 74 43 [2] 50 4d [2] 7b 61 [2] 55 43 [2] 41 58 [2] 4e 42 [2] 50 5f [2] 52 5e [2] 49 58 [2] 55 5f [2] 49 70 }

  condition:
    any of them
}