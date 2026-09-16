rule TTP_XOR_QUAD_CurrentVersionRun_27fc {
  strings:
    $key_27fc = { 74 93 [2] 50 9d [2] 7b b1 [2] 55 93 [2] 41 88 [2] 4e 92 [2] 50 8f [2] 52 8e [2] 49 88 [2] 55 8f [2] 49 a0 }

  condition:
    any of them
}