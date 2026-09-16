rule TTP_XOR_QUAD_CurrentVersionRun_16fc {
  strings:
    $key_16fc = { 45 93 [2] 61 9d [2] 4a b1 [2] 64 93 [2] 70 88 [2] 7f 92 [2] 61 8f [2] 63 8e [2] 78 88 [2] 64 8f [2] 78 a0 }

  condition:
    any of them
}