rule TTP_XOR_QUAD_CurrentVersionRun_253c {
  strings:
    $key_253c = { 76 53 [2] 52 5d [2] 79 71 [2] 57 53 [2] 43 48 [2] 4c 52 [2] 52 4f [2] 50 4e [2] 4b 48 [2] 57 4f [2] 4b 60 }

  condition:
    any of them
}