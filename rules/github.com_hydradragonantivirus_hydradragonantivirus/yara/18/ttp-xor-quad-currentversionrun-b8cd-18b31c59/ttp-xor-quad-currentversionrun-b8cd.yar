rule TTP_XOR_QUAD_CurrentVersionRun_b8cd {
  strings:
    $key_b8cd = { eb a2 [2] cf ac [2] e4 80 [2] ca a2 [2] de b9 [2] d1 a3 [2] cf be [2] cd bf [2] d6 b9 [2] ca be [2] d6 91 }

  condition:
    any of them
}