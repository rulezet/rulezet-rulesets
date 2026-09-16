rule TTP_XOR_QUAD_CurrentVersionRun_302c {
  strings:
    $key_302c = { 63 43 [2] 47 4d [2] 6c 61 [2] 42 43 [2] 56 58 [2] 59 42 [2] 47 5f [2] 45 5e [2] 5e 58 [2] 42 5f [2] 5e 70 }

  condition:
    any of them
}