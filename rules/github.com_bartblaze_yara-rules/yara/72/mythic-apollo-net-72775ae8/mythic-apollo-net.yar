rule Mythic_Apollo_Net
{
meta:
	id = "18TC3KGJ9FKOFcryiefeQ0"
	fingerprint = "v1_sha256_5d24c0ad268da5fcb949f8eb15cefe48196aad0f00c81ca3622c0d88c7ec5e31"
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
	reference = "https://github.com/MythicAgents/Apollo"
	tool = "MYTHIC"

strings:
	$ = "get_C2ProfileManager"
	$ = "get_TaskManager"
	$ = "get_FileManager"
	$ = "get_SocksManager"
	$ = "get_PeerManager"
	$ = "get_ProcessManager"
	$ = "get_InjectionManager"
	$ = "get_TicketManager"
	$ = "get_IdentityManager"
	$ = "get_SleepInterval"
	$ = "get_Jitter"
	
condition:
	9 of them
}