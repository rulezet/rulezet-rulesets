rule TTP_XOR_QUAD_CurrentVersionRun_e7fc {
  strings:
    $key_e7fc = { b4 93 [2] 90 9d [2] bb b1 [2] 95 93 [2] 81 88 [2] 8e 92 [2] 90 8f [2] 92 8e [2] 89 88 [2] 95 8f [2] 89 a0 }

  condition:
    any of them
}