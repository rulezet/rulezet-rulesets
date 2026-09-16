rule TTP_XOR_QUAD_CurrentVersionRun_ed3c {
  strings:
    $key_ed3c = { be 53 [2] 9a 5d [2] b1 71 [2] 9f 53 [2] 8b 48 [2] 84 52 [2] 9a 4f [2] 98 4e [2] 83 48 [2] 9f 4f [2] 83 60 }

  condition:
    any of them
}