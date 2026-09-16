rule INDICATOR_TOOL_PET_BOtB {
    meta:
        author = "ditekSHen"
        description = "Detects Break out the Box (BOtB)"
    strings:
        $s1 = "to unallocated span%%!%c(*big.Float=%s), RecursionDesired: /usr/share/zoneinfo//{Bucket}/{Key+}?acl/{Bucket}?accelerate/{Bucket}?encryption/{Bucket}?" ascii
        $s2 = "exploit CVE-2019-5736 with command: [ERROR] In Enabling CGROUP Notifications -> 'echo 1 > [INFO] CGROUP may exist, attempting exploit regardless" ascii
        $s3 = "main.execShellCmd" ascii
        $s4 = "[*] Data uploaded to:[+]" ascii
        $s5 = "whitespace or line breakfailed to find credentials in the environment.failed to get %s EC2 instance role credentialsfirst" ascii
        $s6 = "This process will exit IF an EXECVE is called in the Container or if the Container is manually stoppedPerform reverse DNS lookups" ascii
        $s7 = "http: request too largehttp://100.100.100.200/http://169.254.169.254/index out of range" ascii
    condition:
       uint16(0) == 0x457f and 6 of them
}