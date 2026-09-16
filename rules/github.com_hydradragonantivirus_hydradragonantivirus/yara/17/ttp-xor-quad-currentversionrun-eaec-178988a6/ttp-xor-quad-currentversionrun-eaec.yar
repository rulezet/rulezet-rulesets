rule TTP_XOR_QUAD_CurrentVersionRun_eaec {
  strings:
    $key_eaec = { b9 83 [2] 9d 8d [2] b6 a1 [2] 98 83 [2] 8c 98 [2] 83 82 [2] 9d 9f [2] 9f 9e [2] 84 98 [2] 98 9f [2] 84 b0 }

  condition:
    any of them
}