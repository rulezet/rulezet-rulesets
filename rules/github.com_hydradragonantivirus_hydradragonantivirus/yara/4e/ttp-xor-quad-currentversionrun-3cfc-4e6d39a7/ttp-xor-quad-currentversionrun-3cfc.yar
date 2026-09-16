rule TTP_XOR_QUAD_CurrentVersionRun_3cfc {
  strings:
    $key_3cfc = { 6f 93 [2] 4b 9d [2] 60 b1 [2] 4e 93 [2] 5a 88 [2] 55 92 [2] 4b 8f [2] 49 8e [2] 52 88 [2] 4e 8f [2] 52 a0 }

  condition:
    any of them
}