rule TTP_XOR_QUAD_CurrentVersionRun_320f {
  strings:
    $key_320f = { 61 60 [2] 45 6e [2] 6e 42 [2] 40 60 [2] 54 7b [2] 5b 61 [2] 45 7c [2] 47 7d [2] 5c 7b [2] 40 7c [2] 5c 53 }

  condition:
    any of them
}