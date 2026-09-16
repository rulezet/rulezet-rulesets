rule Mythic_Apollo
{
meta:
	id = "5agM09gxQMDgPQacwgnLSf"
	fingerprint = "v1_sha256_73dac1002022c73249469d22cc5d9340e82a5b47c7f913d0e309674751031f08"
	version = "1.0"
	date = "2026-01-27"
	modified = "2026-01-27"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Mythic's Apollo agent, a collaborative, multi-platform, red teaming framework."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/its-a-feature/Mythic"
	tool = "MYTHIC"

strings:
	$ = "apollo_tracker_uuid" 
	$ = "mythic_uuid" 
	$ = "MythicMessageEventArgs" 
	$ = "IMythicMessage" 
	$ = "ApolloLogonInformation" 
	$ = "ApolloTokenInformation" 
	$ = "MythicEncryption" 
	$ = "MythicTask" 
	$ = "MythicTaskResponse"
	$ = "MythicTaskStatus" 
	
condition:
	2 of them
}