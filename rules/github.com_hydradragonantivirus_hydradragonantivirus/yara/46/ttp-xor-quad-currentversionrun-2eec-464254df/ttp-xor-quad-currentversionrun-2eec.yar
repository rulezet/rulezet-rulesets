rule TTP_XOR_QUAD_CurrentVersionRun_2eec {
  strings:
    $key_2eec = { 7d 83 [2] 59 8d [2] 72 a1 [2] 5c 83 [2] 48 98 [2] 47 82 [2] 59 9f [2] 5b 9e [2] 40 98 [2] 5c 9f [2] 40 b0 }

  condition:
    any of them
}