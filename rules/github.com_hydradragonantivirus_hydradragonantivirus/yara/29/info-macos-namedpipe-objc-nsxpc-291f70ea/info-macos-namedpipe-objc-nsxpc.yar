rule INFO_MacOS_NamedPipe_ObjC_NSXPC {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-28"
    version     = "1.0"
    description = "check for references to XPC, MacOS low-level interprocess communications, via the NSXPCConnection API classes"

  strings:
    $ = "NSXPCConnection" ascii wide
    $ = "NSXPCInterface" ascii wide
    $ = "NSXPCListener" ascii wide
    $ = "NSXPCListenerEndpoint" ascii wide

  condition:
    any of them
}