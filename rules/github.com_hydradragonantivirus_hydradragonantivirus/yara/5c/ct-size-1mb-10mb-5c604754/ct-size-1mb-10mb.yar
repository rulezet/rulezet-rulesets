rule ct_size_1mb_10mb {
  condition:
    filesize > 1MB and filesize < 10MB
}