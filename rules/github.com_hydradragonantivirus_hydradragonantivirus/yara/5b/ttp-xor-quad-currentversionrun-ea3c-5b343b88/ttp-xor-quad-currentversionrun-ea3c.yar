rule TTP_XOR_QUAD_CurrentVersionRun_ea3c {
  strings:
    $key_ea3c = { b9 53 [2] 9d 5d [2] b6 71 [2] 98 53 [2] 8c 48 [2] 83 52 [2] 9d 4f [2] 9f 4e [2] 84 48 [2] 98 4f [2] 84 60 }

  condition:
    any of them
}