rule ct_size_1kb_10kb {
  condition:
    filesize > 1KB and filesize < 10KB
}