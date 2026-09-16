rule TTP_XOR_QUAD_CurrentVersionRun_eb0c {
  strings:
    $key_eb0c = { b8 63 [2] 9c 6d [2] b7 41 [2] 99 63 [2] 8d 78 [2] 82 62 [2] 9c 7f [2] 9e 7e [2] 85 78 [2] 99 7f [2] 85 50 }

  condition:
    any of them
}