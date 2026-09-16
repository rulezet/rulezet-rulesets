rule TTP_XOR_QUAD_CurrentVersionRun_320d {
  strings:
    $key_320d = { 61 62 [2] 45 6c [2] 6e 40 [2] 40 62 [2] 54 79 [2] 5b 63 [2] 45 7e [2] 47 7f [2] 5c 79 [2] 40 7e [2] 5c 51 }

  condition:
    any of them
}