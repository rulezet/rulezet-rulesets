rule TTP_XOR_QUAD_CurrentVersionRun_062c {
  strings:
    $key_062c = { 55 43 [2] 71 4d [2] 5a 61 [2] 74 43 [2] 60 58 [2] 6f 42 [2] 71 5f [2] 73 5e [2] 68 58 [2] 74 5f [2] 68 70 }

  condition:
    any of them
}