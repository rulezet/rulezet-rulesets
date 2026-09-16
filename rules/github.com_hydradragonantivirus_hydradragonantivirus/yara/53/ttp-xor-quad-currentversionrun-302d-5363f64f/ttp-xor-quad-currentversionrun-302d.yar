rule TTP_XOR_QUAD_CurrentVersionRun_302d {
  strings:
    $key_302d = { 63 42 [2] 47 4c [2] 6c 60 [2] 42 42 [2] 56 59 [2] 59 43 [2] 47 5e [2] 45 5f [2] 5e 59 [2] 42 5e [2] 5e 71 }

  condition:
    any of them
}