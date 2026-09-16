rule TTP_XOR_QUAD_CurrentVersionRun_0fff {
  strings:
    $key_0fff = { 5c 90 [2] 78 9e [2] 53 b2 [2] 7d 90 [2] 69 8b [2] 66 91 [2] 78 8c [2] 7a 8d [2] 61 8b [2] 7d 8c [2] 61 a3 }

  condition:
    any of them
}